rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 55 8B EC 8B 45 08 8B 48 14 56 6A 35 6A 00 51 51 }
        $pattern2 = { 59 BB 07 FE 55 8B 55 8B 45 08 EC 8B 45 08 8B 4D 0C 83 C4 14 52 8B 16 50 51 FF D2 5E 5D }

    condition:
        any of them
}