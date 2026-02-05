rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 EC 48 56 FF 15 C0 A0 41 00 }  //Trace //1, Bypass call to [0041A0C0h]
        $pattern1 = { 0A 14 EC 4A 55 8B EC E8 BB 21 00 00 83 F8 01 74 20 }  //Trace //2, Bypass push instruction
        $pattern2 = { 00 40 67 D6 51 51 E8 5A 29 01 00 }  //Trace //1, Bypass push instruction

    condition:
        any of them
}