rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 F8 01 }  // Push/Pop/Call + EAX cmp
        $pattern1 = { C1 E8 08 A8 01 75 10 FF 75 08 E8 ?? ?? ?? ?? }  // SHR/TEST/JNE + PUSH
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? FF 15 A0 F1 42 00 }  // PUSH/CALL + ExitProcess call

    condition:
        any of them
}