def countLetters(inputTxt):
    letterCount = [0] * 26
    for letter in inputTxt:
        if letter.isalpha():
            pos = ord(letter.lower()) - ord('a')
            letterCount[pos] += 1
    return letterCount

def getFrequency(inputTxt):
    letterCount = countLetters(inputTxt)
    total = sum(letterCount)
    frequency = [0] * 26
    for i in range(26):
        frequency[i] = letterCount[i] / total
        #convert to percentage and round to 2 decimal places
        frequency[i] = round(frequency[i] * 100, 2)
        #give a tuple of the letter and its frequency
        frequency[i] = (alphabets[i], frequency[i])
    return frequency

# txt = "This is a test"

alphabets = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

knownFrequencies = [12.7, 9.06, 8.17, 7.51, 6.97, 6.75, 6.33, 6.09, 5.99, 4.25, 4.02, 2.78, 2.76,
                           2.41, 2.36, 2.23, 2.01, 1.97, 1.93, 1.49, 0.99, 0.77, 0.15, 0.15, 0.09, 0.07]

alphaFrequencies = ['e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', 'q', 'z']

#map the highest frequency letter of the input to 5 and map rest of the to 0 and return the tuple with the letter and the mapped value
def mapFrequency(inputTxt):
    #get the frequency of the input
    frequency = getFrequency(inputTxt)
    #sort the frequency in descending order
    frequency.sort(key=lambda x: x[1], reverse=True)
    #create a dictionary to map the frequency
    frequencyMap = {}
    for i in range(26):
        frequencyMap[frequency[i][0]] = 0
    #map the highest frequency letter to 5
    frequencyMap[frequency[0][0]] = 5
    #return the frequency map
    return frequencyMap

def countDoubles(inputTxt):
    count = 0
    for i in range(len(inputTxt) - 1):
        if inputTxt[i] == inputTxt[i + 1]:
            count += 1
    return count

#Look for doubled letters. Frequent doubles are the pairs 'ss', 'll', 'oo', 'ee', 'nn', 'pp'. 
#If the input has any of these pairs, return the letter and the mapped value - we will use trail and error to find the correct letter
def findDoubledLetters(inputTxt):
    doublenumber = countDoubles(inputTxt)
    if doublenumber == 0:
        return mapFrequency(inputTxt)
    letters = 'slonp'    
    letter = letters[0] #default letter
    if letter == 's':
        value = 19
    elif letter == 'l':
        value = 12
    elif letter == 'o':
        value = 15
    elif letter == 'n':
        value = 14
    elif letter == 'p':
        value = 16
    else:
        value = 27
    
    frequencyMap = mapFrequency(inputTxt)
    #look for the pairs (any two same letters) in the input
    for i in range(len(inputTxt) - 1):
        if inputTxt[i] == inputTxt[i + 1]:
            frequencyMap[inputTxt[i]] = value
            return frequencyMap
    return frequencyMap

def decrypt(inputTxt, frequencyMap):
    decrypted = ""
    for letter in inputTxt:
        if letter.isalpha():
            if letter.islower():
                decrypted += alphabets[(ord(letter) - ord('a') + frequencyMap[letter]) % 26]
            else:
                decrypted += alphabets[(ord(letter.lower()) - ord('a') + frequencyMap[letter.lower()]) % 26].upper()
        else:
            decrypted += letter
    return decrypted

def bruteforce(inputTxt):
    frequencyMap = findDoubledLetters(inputTxt)
    #sort the frequency map in descending order
    frequencyMap = sorted(frequencyMap.items(), key=lambda x: x[1], reverse=True)
    #bruteforce the values which are zero from 1 to 26 (excluding the ones which are already mapped)
    for i in range(26):
        if frequencyMap[i][1] == 0:
            for j in range(1, 26):
                frequencyMap[i] = (frequencyMap[i][0], j)
                #decrypt the input using the frequency map
                decrypted = decrypt(inputTxt, dict(frequencyMap))
                with open('output.txt', 'a') as f:
                    #write the decrypted input to a file
                    f.write(decrypted)
                    f.write("\n")

    return frequencyMap
txt = "ziwujddjfqymrpjodwsvgyowbjdkwhwqziwpziwwgbxfgxjpziwigphfgxzfjzpgqybsqdwbgrgpzgpwsjkqymzjfgphwgvijziwpwgvijywqbmjqymgzgbrwwhjusqdwbrwpijcpgudxbzgpzqymjyziwupjyzjujywjuziwsudqwbogvtgyhujpziowzfwwyziwsgzgpgzwjusqdwbrwpijcpqzhjwbziqbcyzqdziwzpgqybvjddqhwgyhvpcbiziwudxzjhwgzifigzqbziwzjzgdhqbzgyvwziwudxigbudjfyziwudxgvzcgddxiqzbwgvizpgqygyqyuqyqzwycsowpjuzqswbowujpwqzmwzbvpcbiwhgyhjywvjcdhbjdkwziwrpjodwsziwigphfgxfqzirwyvqdgyhrgrwpoxbcssqymgyqyuqyqzwbwpqwbjuhqbzgyvwbziwwgbxfgxqbgbujddjfbbqyvwziwzpgqybgpwsqdwbgrgpzgyhwgvizpgqyqbmjqymsqdwbgyijcpqzzgtwbijcpbujpziwzpgqybzjvjddqhwziwpwujpwziwudxfgbudxqymujpzfjijcpbbqyvwziwudxfgbudxqymgzgpgzwjusqdwbrwpijcpziwudxscbzigkwudjfysqdwbzigzqbgddziwpwqbzjqzfiwyziqbrpjodwsfgbrjbwhzjajiykjyywcsgyyiwqsswhqgzwdxpwrdqwhsqdwbqzqbkwpxbzpgymwbgqhziwrjbwpoczywgpdxwkwpxjywzpqwbzjbcsziwqyuqyqzwbwpqwbfigzhjxjcswgybzpgymwgbtwhkjyywcsgyyzigzqbijfqhqhqz"
# txt = "abcdee"
#run brute force function and write the output to a file
output = bruteforce(txt)



print(output)





