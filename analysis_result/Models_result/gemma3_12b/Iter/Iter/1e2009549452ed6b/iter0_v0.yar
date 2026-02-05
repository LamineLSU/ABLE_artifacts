rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 20 00 }
        $pattern1 = { FF 15 84 A0 20 00 6A 02 EB F6 }
        $pattern2 = { 64 A1 30 00 00 8B 40 68 C1 E8 08 A8 01 }

    condition:
        any of them
}