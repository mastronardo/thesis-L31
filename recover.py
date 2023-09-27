from pyseltongue import PlaintextToHexSecretSharer
from cryptography.fernet import Fernet, InvalidToken
import inquirer
import animation
import hashlib
from json import load
import pymongo
import csv
from datetime import datetime
from time import time
from binascii import Error
import argparse
from os import mkdir

def asking(min):
    while True:
        try:
            num = int(input('Type a number: '))
            break
        except:
            print('You should write a number...')
    while num < min:
        try:
            num = int(input('Type a number: '))
        except:
            print('You should write a number...')
    
    return num

def YesOrNo():
    questions = [
        inquirer.List('YesOrNo',
                    choices=['Yes', 'No'],
                ),
    ]
    answer = inquirer.prompt(questions)['YesOrNo']
    return answer

def open_json(file):
    with open (file, 'r') as f:
        info = load(f)
    return info

def write_csv(values, i):
    # generating csv file with execution times
    with open('output/csv/execution_times_recover' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.csv', 'w', newline='') as csvfile:
        fieldnames = ['Iteration', 'Execution Time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for i, time_value in enumerate(values, start=1):
            writer.writerow({'Iteration': (i+1), 'Execution Time': time_value})

def decrypt_info(key):
    # decrypting share and string proof
    while True:
        try:
            cipher_suite = Fernet(key)
            encrypted_share = input('Enter your encrypted share: ')
            encrypted_proof = input('Enter your encrypted string proof: ')

            share = cipher_suite.decrypt(encrypted_share.encode('UTF-8'))
            print("\nDecrypted share:", share.decode('utf-8'))
            string_proof = cipher_suite.decrypt(encrypted_proof.encode('UTF-8'))
            print("\nDecrypted string proof:", string_proof.decode('utf-8'))
            break
        except (ValueError, Error, InvalidToken):
            print('Something went wrong...')

def find_mongo(share, client):
    # check if the share exists on mongodb
    db = client["SecretSharing"]
    collection = db["SharedSecrets"]
    result = collection.find_one({'$or':[  {"shares":share}, { "subshares":share}]}, {"shares": 1, "subshares": 1})
    return result

def RecoverSecret(shares, salt, client):
    while True:
        enter = input('Enter your share: ')
        beggining = time()
        # check the verifiability
        check = input('Enter your string proof: ')
        m = hashlib.sha256(enter.encode('UTF-8') + salt.encode('UTF-8'))
        string_proof = m.hexdigest()

        # if the share is intact, exists on mongodb
        # and has not already been inserted (in this program execution), it will be inserted into the list
        if check == string_proof:
            if (enter not in shares) and (find_mongo(enter, client) != None):
                print('This share is intact!')
                shares.append(enter)
                end1 = time()-beggining
            else:
                print('You have already entered this share or it has expired.')
        else:
            print('Something went wrong...')

        print('Do you have another share?')
        answer = YesOrNo()
        if answer == 'Yes':
            continue

        if len(shares)>1:
            while True:
                beggining = time()
                # Recover
                wait = animation.Wait('spinner', 'Recovering... It may take a while.. ')
                wait.start()
                message = PlaintextToHexSecretSharer.recover_secret(shares)
                wait.stop()
                end2 = time()-beggining
                # Check threshold
                if not message.isalnum() and (not message[0].isalpha() or message[1]!='-' or not message[2:].isalnum()):
                    print('Not enough shares.\nDo you have another share?')
                    answer = YesOrNo()
                    if answer == 'Yes':
                        break
                    else:
                        print('Bye Bye')
                        return
                else:
                    if message.isalnum():
                        beggining = time()
                        print('Original message:\n\n'+message)
                        end3 = time()-beggining
                        end = end1 + end2 + end3
                        return end
                    else:
                        beggining = time()
                        # if the secret is a level 1 share, print its string proof too
                        print('Original message: '+message)
                        m = hashlib.sha256(message.encode('UTF-8') + salt.encode('UTF-8'))
                        string_proof = m.hexdigest()
                        print('\nString Proof: '+string_proof)
                        end3 = time()-beggining
                        end = end1 + end2 + end3
                        return end

        elif len(shares)==0:
            print('No valid shares')
            return
        else:
            print('One share is not enough!')
            return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--salt', type=str, help='salt file')
    parser.add_argument('-k', '--key', type=str, help='key file')
    parser.add_argument('-m', '--mongo', type=str, help='ip mongo')
    args = parser.parse_args()

    # Creating directory if it doesn't exist
    try:
        mkdir('output/csv')
    except:
        pass

    print('How many times do you want to run the program?')
    t = asking(1)

    beggining = time()
    # Checking if the database is available, otherwise the program will not run
    client = pymongo.MongoClient("mongodb://"+args.mongo+":27017")
    try:
        client.admin.command('ping')
    except:
        print('The database is not available.\nTry again later or ask administrator.')
        return

    # Getting the salt
    salt = open_json(args.salt)['salt']

    # Getting the key
    key = bytes(open_json(args.key)['key'], "utf-8")
    end1 = time()-beggining

    execution_times=[]
    for i in range(0, t):
        shares = []
        print('\nHi, do you need to decrypt share and string proof?')
        answer = YesOrNo()
        if answer == 'Yes':
            decrypt_info(key)
            while True:
                print('Hi, do you need to decrypt others shares and strings proof?')
                answer = YesOrNo()
                if answer == 'Yes':
                    decrypt_info(key)
                else:
                    end2 = RecoverSecret(shares, salt, client)
                    end = end1 + end2
                    execution_times.append(end)
                    break

        else:
            end2 = RecoverSecret(shares, salt, client)
            end = end1 + end2
            execution_times.append(end)

    write_csv(execution_times, i)
    # Closing connection with mongodb
    client.close()

if __name__ == '__main__':
	main()
