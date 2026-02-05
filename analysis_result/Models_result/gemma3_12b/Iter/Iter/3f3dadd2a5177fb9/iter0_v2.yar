rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 FF 15 8C C1 33 00 }  //Push and Call (10 bytes)
        $pattern1 = { FF 15 3C C1 33 00 50 FF 15 40 C1 33 00 } //First three instructions (15 bytes)
        $pattern2 = { 8B 8C FF 15 8C C1 33 00 } //Context before final call (11 bytes)

    condition:
        any of them
}