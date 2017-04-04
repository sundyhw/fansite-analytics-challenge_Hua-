import sys # for passing string                                                                                                                                                   
import re  # for string operations    

sys_list = sys.argv

fhand_read  = open(sys_list[1])  # open log.txt
fhand_write1 = open(sys_list[2],"w") # for feature 1 
fhand_write2 = open(sys_list[3],"w") # for feature 2
fhand_write3 = open(sys_list[4],"w") # for feature 3  
fhand_write4 = open(sys_list[5],"w") # for feature 4  
fhand_write5 = open(sys_list[6],"w") # for additional feature 1  
fhand_write6 = open(sys_list[7],"w") # for additional feature 2  
fhand_write7 = open(sys_list[8],"w") # for additional feature 3
fhand_write8 = open(sys_list[9],"w") # for additional feature 4  

# for feature 1
IP_count = dict() # creat dictionary for key(IP), value(count)
IP_list = list() # for sorting

# for feature 2
resource_sum = dict() # creat dictionary for key(resource), value(sum byte)  
resource_list = list() # for sorting 

# for feature 3
second_count = [0]*2419200 #  create list for count urls in one second                                                                                                             
hour_count = [0]*(2419200 - 3601) #  create list for summing counts in one hour

# for feature 4
warn_list = list() # create a list of IPs with one or two record, format as [IP, first_time, second_time]                                                           
ban_list = list() # creata a list of ban IPs, format as [IP, time]

# for additional feature 1
add1_dict1 = dict() # creat dictionary for key(IP), value(count fail logins)                                                                                   
add1_dict2 = dict() # creat dictionary for key(IP), value(count successful logins)  

# for additional feature 2 
add2_dict = dict() # creat dictionary for key(IP), value(count of three consecutive fail logins)                                                                                  

# for additional feature 3 

# for additional feature 4

for line in fhand_read:
    line.rstrip()    
    
    # feature 1
    IP = re.findall('([0-9a-zA-Z.]+) - -', line) # extract IP
    IP = IP[0]
    IP_count[IP] = IP_count.get(IP, 0)+1 # create IP as key in dictionary if not exists, add 1 as value if exists
    
    # feature 2
    resource = re.findall('[A-Z].* (.+) HTTP/1.0', line) # extract resource
    byte = re.findall(' HTTP/1.0" [0-9].* ([0-9\-].*)', line) # extract byte
    if len(resource) == 0 or len(byte) == 0 or byte[0] == '-' or resource[0] == '/':
        feature2_flag = 1            
    else:
        resource_sum[resource[0]] = resource_sum.get(resource[0], 0)+int(byte[0]) # create resource as key in dictionary if not exists, add byte as value if exists 

    # feature 3
    time = re.findall('\[(.+)\]', line)[0]
    time_split = re.split('[/ : -]',time)
    day, hour, minute, second = int(time_split[0]), int(time_split[3]), int(time_split[4]), int(time_split[5])
    current_second =  ((day*24 + hour)*60 + minute)*60 + second
    second_count[(current_second - 86401)] += 1

    # feature 4 
    if 'POST' in line:   #check if type is log in                                                                                                                  
        IP = re.findall('([0-9a-zA-Z.]+) - -', line)
        IP = IP[0]
        code = re.findall(' HTTP/1.0" ([0-9].*) [0-9\-].*', line)
        time = re.findall('\[(.+)\]', line)[0]
        time_split = re.split('[/ : -]',time)
        day, hour, minute, second = int(time_split[0]), int(time_split[3]), int(time_split[4]), int(time_split[5])
        converted_second =  ((day*24 + hour)*60 + minute)*60 + second # convert day, hour, minute, second into seconds

        # additional feature 1                                                                                                                                                    
        if code[0] == '401':
            add1_dict2[IP] = add1_dict2.get(IP, 0)+1
        else:
            add1_dict1[IP] = add1_dict1.get(IP, 0)+1


    # feature 4          
        # Step 1, update records in ban_list                                                                                                                                       
        for i, s in enumerate(ban_list):
            if (converted_second - s[1]) >= 301:  # if 5 minutes have passed, remove this IP from ban_list
                ban_list.pop(i)
        # Step 2, update records in warn_list                                                                                                                                      
        for i, s in enumerate(warn_list):
            if s[2] == -1:      # has one record 
                if (converted_second - s[1]) >= 21: # if the only record has passed the 20 seconds window, remove this IP from warn_list
                 warn_list.pop(i)
            else:               # has two records                                                                                                                 
                if (converted_second - s[2]) >= 21:  # if the second record has passed the 20 seconds window, remove this IP from warn_list 
                    warn_list.pop(i)
                elif (converted_second - s[1]) >= 21 and (converted_second - s[2]) < 21: # if only the first record has passed the 20 seconds window, 
                    s[1] = s[2] # move the second record to the first recond
                    s[2] = -1
        
        # Step 3, check if IP is in ban_list  
        flag_ban = 0  # flag for flow control    
        for j in range(len(ban_list)):
            if ban_list[j][0] == IP: 
                flag_ban = 1
                fhand_write4.write(line) # if in ban list, write the line to feature 4
                fhand_write7.write(line) # if in ban list, write the line to addtional feature 3
                if code[0] != '401':
                    fhand_write8.write(line) # if in ban list, write the line to addtional feature 4   
                break
        if flag_ban == 1:  # stop following commands in current loop
            continue
        
        # Step 4, case where IP in warn_list or should be added to warn_list
        if code[0] == '401':  # check if it is a failed login
            flag_find = 0  # flag for find or not                                                                                                                                 
            # Step 4-1 check the case of one record of warning
            for i, s in enumerate(warn_list):
                if IP == s[0] and s[2] == -1:
                    s[2] = converted_second # put current recording as the second current
                    flag_find = 1
                    break
            # Step 4-2 check the case of two record of warning 
                elif IP == s[0] and s[2] != -1:
                    warn_list.pop(i) # remove current IP from warn_list
                    ban_list.append([IP, converted_second]) # add current IP to ban_list
                    flag_find = 1
                     # additional feature 2  
                    add2_dict[IP] = add2_dict.get(IP, 0)+1
                    break
            # Step 4-3 check the case where IP not in warn_list, then add the IP as first record
            if flag_find == 0:  # IF IP not 
                warn_list.append([IP , converted_second , -1])
        
        # Step 4, a successful log in erase all warn list 
        else: 
            for i, s in enumerate(warn_list):
                if IP == s[0]:
                    warn_list.pop(i)
                    break

    # additional feature 3, print other activities in 'GET'
    else: 
        for j in range(len(ban_list)):
            if ban_list[j][0] == IP:
                fhand_write7.write(line)
                break

# sorting and printing for feature 1        
for IP_address, IP_freq in IP_count.items():
    IP_list.append((IP_freq, IP_address)) # convert dictionary to list for sorting
IP_list.sort(reverse = True) #sort the list
for IP_freq, IP_address in IP_list[:10]:
    fhand_write1.write(str(IP_address) + ',' + str(IP_freq) + '\n') # output feature 1

# sorting and printing for feature 2    
for resource_name, resource_size in resource_sum.items():
    resource_list.append((resource_size, resource_name)) # convert dictionary to list for sorting 
resource_list.sort(reverse = True)
for resource_size, resource_name in resource_list[:10]:
    fhand_write2.write(str(resource_name) + '\n') # output feature 2

# summing, sorting, and printing for feature 3
for j in range(current_second-86400):
    hour_count[j] = sum(second_count[j:(j+3601)])  # summing counts of 3600 seconds in 1 hour

sort_index =  sorted(range(len(hour_count)), key=lambda i: hour_count[i], reverse=True)[:10] # sort hour_count
for j in sort_index:
    current_day = (j+1)/86400 + 1   # time conversion, day
    current_hour = ((j+1)% 86400) / 3600  # time conversion, hour   
    current_miniute = (((j+1)% 86400) % 3600) / 60 # time conversion, minite
    current_second = (((j+1)% 86400) % 3600) % 60  # time conversion, second 
    fhand_write3.write( "%02d/Jul/1995:%02d:%02d:%02d -0400,%d" % (current_day, current_hour, current_miniute, current_second, hour_count[j]) + '\n') # output feature 3             
# summing and printing for additional feature 1
for IP, count in add1_dict2.items():
    neg_counts = count
    pos_counts = add1_dict1.get(IP, 0)
    fhand_write5.write(str(IP) + ',' + str(neg_counts) + ',' + str(neg_counts+pos_counts)+ ',' + str(float(neg_counts)/(float(neg_counts)+float(pos_counts))) + '\n')

# printing for additional feature 2
for IP, count in add2_dict.items():
    fhand_write6.write(str(IP) + ',' + str(count) + '\n')


fhand_write1.close()    
fhand_write2.close()
fhand_write3.close()
fhand_write4.close()
fhand_write5.close()
fhand_write6.close()
fhand_write7.close()
fhand_write8.close()
