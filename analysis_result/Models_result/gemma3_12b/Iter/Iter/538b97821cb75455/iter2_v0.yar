rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=00405823+0,action0=skip,bp1=00405829+0,action1=skip,bp2=0040581B+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { 59 FF 75 08 FF 15 1C E0 40 00 }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 }

    condition:
        any of them
}