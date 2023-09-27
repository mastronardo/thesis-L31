from pyseltongue import PlaintextToHexSecretSharer
from cryptography.fernet import Fernet, InvalidToken
import pyqrcode
import inquirer
import animation
import hashlib
from requests import get
from socket import gethostbyname, gethostname
from json import load, dump
from datetime import datetime
from time import time
from binascii import Error
import argparse
import csv
import pymongo
from os import mkdir
import graph

mapping = {}
count = 1

def open_json(name_file):
    with open (name_file, 'r') as f:
        info = load(f)
    return info

def create_json(dictionary, name_file):
    with open(name_file, 'w') as f:
        dump(dictionary, f, indent=4)

def insert_mongo(dictionary, client):
    db = client["SecretSharing"]
    collection = db["SharedSecrets"]

    # dictionary manipulation for import into mongodb
    mapping = {}
    mapping['FingerPrint'] = list(dictionary.keys())[0]
    mapping['shares'] = list(dictionary[mapping['FingerPrint']]['shares'].keys())
    mapping['subshares'] = []
    for share in mapping['shares']:
        for subshare in list(dictionary[mapping['FingerPrint']]['shares'][share].keys()):
            for subsub in list(dictionary[mapping['FingerPrint']]['shares'][share][subshare]['share'].keys()):
                mapping['subshares'].append(subsub)

    collection.insert_one(mapping)

def write_csv(values, i):
    # generating csv file with execution times
    with open('output/csv/execution_times_share' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.csv', 'w', newline='') as csvfile:
        fieldnames = ['Iteration', 'Execution Time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for i, time_value in enumerate(values, start=1):
            writer.writerow({'Iteration': i, 'Execution Time': time_value})

def FingerPrint_generation(name_file):
    # generating FingerPrint with md5 from user's info, local IP and public IP
    global mapping
    with open (name_file, 'r') as f:
        info = load(f)

    Sum = bytes(0)
    for key in list(info.keys()):
        Sum += bytes(info[key], "utf-8")

    localIP = bytes(str(gethostbyname(gethostname())), "utf-8")
    publicIP = bytes(get("https://api.ipify.org").text, "utf-8")

    FingerPrint = hashlib.md5(Sum + localIP + publicIP)
    secret = FingerPrint.hexdigest()
    mapping[secret] = {}
    return secret

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

def output():
    # Select type of shares output
    scale = 0
    questions = [
        inquirer.List('format',
                    message='Select the format of output images',
                    choices=['png', 'svg', 'terminal'],
                ),
    ]
    format_output = inquirer.prompt(questions)['format']

    # Select size of shares output
    if format_output != 'terminal':
        questions = [
            inquirer.List('scale',
                        message='Size of output images',
                        choices=['Small', 'Medium', 'Large'],
                    ),
        ]
        answers = inquirer.prompt(questions)
        if answers['scale'] == 'Small':
            scale = 2
        elif answers['scale'] == 'Medium':
            scale = 4
        elif answers['scale'] == 'Large':
            scale = 8

    return format_output, scale

def print_output(share, img, format_output, scale, levels):
    if format_output == 'png':
        if levels > 1:
            img.png('output/shares/' + share[0] + 'subshare-' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.png', scale)
        else:
            img.png('output/shares/' + share[0] + 'share-' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.png', scale)
    elif format_output == 'svg':
        if levels > 1:
            img.svg('output/shares/' + share[0] + 'subshare-' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.svg', scale)
        else:
            img.svg('output/shares/' + share[0] + 'share-' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.svg', scale)
    elif format_output == 'terminal':
        print(img.terminal())

def revealing_threshold(parts):
    if parts > 2:
        min_threshold = 2
        max_threshold = parts
        thresholds = [x for x in range(min_threshold, max_threshold+1)]
        questions = [
            inquirer.List('threshold',
                        message='How many shares should be enough for decryption? (Most secure: ' + str(max_threshold) + ')',
                        choices=thresholds,
                    ),
        ]
        answer = inquirer.prompt(questions)
        threshold = int(answer['threshold'])
    else:
        threshold = parts
    
    return threshold

def levelup(shares, parts):
    Min = 1
    Max = parts
    ListofShares = [x for x in range(Min, Max+1)]
    questions = [
        inquirer.List('levelup',
                    message='Which share will level up?',
                    choices=ListofShares,
                ),
    ]
    answer = inquirer.prompt(questions)
    levelup = int(answer['levelup'])
    subsecret = shares[levelup-1]
    return subsecret

def proof(share, salt, key):
    # generating string proof
    m = hashlib.sha256(share.encode('UTF-8') + salt.encode('UTF-8'))
    proof_string = m.hexdigest()
    
    # encrypting share and string proof
    try:
        cipher_suite = Fernet(key)
        cipher_share = cipher_suite.encrypt(share.encode('UTF-8'))
        cipher_proof = cipher_suite.encrypt(proof_string.encode('UTF-8'))
        dic = {'SHARE': cipher_share, 'STRING PROOF': cipher_proof, 'SALT': salt}
    except (ValueError, Error, InvalidToken):
            print('Invalid key format.')
            return
    return dic

def SecretShare(secret, threshold, parts, format_output, scale, salt, levels, key, FingerPrint=None):
    global mapping, count
    # Share
    wait = animation.Wait('spinner', 'Generating randomness.. It may take a while.. ')
    wait.start()
    shares = PlaintextToHexSecretSharer.split_secret(secret, threshold, parts)
    wait.stop()
    
    if levels > 1:
        print('SS Level ' + str(levels) + ' about: ' + str(secret) + '\n',shares)
        
        # generating dictionary with all information
        if count == 1:
            subshares = 'subshares' + str(count)
            subthreshold = 'subthreshold' + str(count)
            mapping[FingerPrint]['shares'][secret] = {
                subshares: {subthreshold: threshold}
            }
            mapping[FingerPrint]['shares'][secret][subshares]['share'] = {}
            for share in shares:
                
                mapping[FingerPrint]['shares'][secret][subshares]['share'][share] = {}
            count += 1
        else:
            while True:
                subshares = 'subshares' + str(count)
                if subshares not in mapping[FingerPrint]['shares'][secret]:
                    subthreshold = 'subthreshold' + str(count)
                    mapping[FingerPrint]['shares'][secret][subshares] = {
                        subthreshold: threshold
                    }
                    mapping[FingerPrint]['shares'][secret][subshares]['share'] = {}
                    for share in shares:
                        
                        mapping[FingerPrint]['shares'][secret][subshares]['share'][share] = {}
                    count += 1
                    break
                else:
                    count += 1

    else:
        print('SS Level 1\n',shares)
        # generating dictionary with all information
        mapping[secret]={
            'threshold': threshold,
            'shares':{}
        }
        for share in shares:
            mapping[secret]['shares'][share]={}
        
    for share in shares: # Create output for each share
        dic = proof(share, salt, key)
        img = pyqrcode.create(str(dic))
        print_output(share, img, format_output, scale, levels)

    return shares

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--info', type=str, help='info file')
    parser.add_argument('-s', '--salt', type=str, help='salt file')
    parser.add_argument('-k', '--key', type=str, help='key file')
    parser.add_argument('-m', '--mongo', type=str, help='ip mongo')
    args = parser.parse_args()

    # Creating directories if they don't exist
    try:
        mkdir('output/shares')
        mkdir('output/graphs')
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
    end1 = time()-beggining

    execution_times=[]
    for i in range(0, t):
        beggining = time()
        try:
            # Getting the salt
            salt = open_json(args.salt)['salt']

            # Getting the key
            key = bytes(open_json(args.key)['key'], "utf-8")
            try:
                Fernet(key)
            except (ValueError, Error, InvalidToken):
                print('Invalid key format.')
                return

            # FingerPrint generation (the secret)
            secret = FingerPrint_generation(args.info)
        except FileNotFoundError:
            print('The program expected json files. Retry!')
            return

        print('This is your FingerPrint: ', secret)
        end2 = time()-beggining

        """
        Secret Sharing
        """
        # Select number of shares
        print("Hi, how many shares do you want to create? (Min: 2)")
        parts = asking(2)

        # Select revealing threshold
        threshold = revealing_threshold(parts)

        # Select type and size of shares output
        format_output, scale = output()

        beggining = time()
        # Secret-share the message using Shamir's secret sharing scheme.
        levels = 1
        shares = SecretShare(secret, threshold, parts, format_output, scale, salt, levels, key)
        end3 = time()-beggining


        """
        Multilevel SS
        """
        print('Do you wanna use Multilevel SS?')
        answer = YesOrNo()
        if answer == 'Yes':
            while True:
                print("Choose the level of SS. (Min: 2)")
                levels = asking(2)

                # Select which share will level up
                subsecret = levelup(shares, parts)

                # Select revealing subthreshold
                subthreshold = revealing_threshold(levels)

                beggining = time()
                # Select type and size of subshares output
                format_output, scale = output()

                # Secret-share the level 1 share using Shamir's secret sharing scheme.
                SecretShare(subsecret, subthreshold, levels, format_output, scale, salt, levels, key, FingerPrint=secret)
                end4 = time()-beggining

                print('Do you wanna use again Multilevel SS?')
                answer = YesOrNo()
                if answer == 'No':
                    beggining = time()
                    # generating and saving graph
                    graph.visit(mapping)
                    graph.graph.write_png('output/graphs/graph-' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.png')
                    
                    insert_mongo(mapping, client) # inserting the dictionary into mongodb
                    end5 = time()-beggining
                    end = end1 + end2 + end3 + end4 + end5
                    execution_times.append(end)
                    print('Bye Bye')
                    break

        else:
            beggining = time()
            # generating and saving graph
            graph.visit(mapping)
            graph.graph.write_png('output/graphs/graph-' + str(datetime.now()).replace(" ", "_").replace(".", "-").replace(":", "-")[0:19] + '.png')
            
            insert_mongo(mapping, client) # inserting the dictionary into mongodb
            end4 = time()-beggining
            end = end1 + end2 + end3 + end4
            execution_times.append(end)
            print('Bye Bye')

    write_csv(execution_times, i)
    # Closing connection with mongodb
    client.close()

if __name__ == '__main__':
	main()
