rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 C1 E8 08 A8 01 75 10 FF 75 08 } //TEST AL, 01h + JNE
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 } //FS:[00000030h] access
        $pattern2 = { 83 F8 01 74 20 64 A1 30 00 00 00 8B 40 68 } //CMP EAX, 01h

    condition:
        any of them
}