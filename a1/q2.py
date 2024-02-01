#frequency attack on the substitution cipher

def find_key(encoded_text):
    freq={}
    dkey={}
    count=0
    characters='etaoinsrhdlucmfywgpbvkxqjz'
    for i in "".join(encoded_text.split()):
        if(i in freq):
            freq[i]+=1
        else:
            freq[i]=1
    res = {key: val for key, val in sorted(freq.items(), key = lambda ele: ele[1], reverse = True)}
    for i in res:
        dkey[i]=characters[count]
        count+=1
    dkey[' ']=' '
    dkey['.']='.'
    dkey[',']=',' 
    dkey['\n']='\n'    
    return dkey

def decoded_message(encoded_text,key):
    decrypted_message=''
    for i in encoded_text:
        decrypted_message+=(key[i])
    return decrypted_message

encoded_text=input("Enter the encoded text: ")

dkey=find_key(encoded_text)

print(dkey)
print("==============================================================================================================")
print(decoded_message(encoded_text,dkey))


    