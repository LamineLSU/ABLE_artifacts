rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? CA 11 60 00 }
        $pattern1 = { 0F 84 ?? ?? ?? ?? FD FF FF FF }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? FD FF FF FF }

    condition:
        any of them
}