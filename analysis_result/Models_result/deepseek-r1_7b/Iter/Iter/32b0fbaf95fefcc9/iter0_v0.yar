rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection for potential IDA obfuscation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A C9 ?? 5A 8B CE E8 ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { FF 35 10 93 52 00 FF 15 5C CC 24 C0 00 ?? ?? ?? ?? ?? 8B 45 ?? } 
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? }
    condition:
        any of them
}