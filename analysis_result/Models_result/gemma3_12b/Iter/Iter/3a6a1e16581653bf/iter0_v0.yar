rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 } //Memory access + shift
        $pattern1 = { FF 75 08 FF 15 3C E1 C0 00 50 FF 15 40 E1 C0 00 } //Push + Call + Push + Call
        $pattern2 = { FF 75 08 E8 0B 00 00 00 59 FF 75 08 } //Push + Call + Call + Pop + Push

    condition:
        any of them
}