rule Bypass_Sample {
meta:
description = "Evasion bypass rule"
cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

strings:
$pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? FF 15 08 E3 48 00 }
$pattern1 = { 55 8B EC 83 EC 0C 6A 7C 58 68 10 66 80 ?? 50 }

condition:
any of them
}