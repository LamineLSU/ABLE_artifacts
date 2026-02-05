rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x003B617A+0,action0=skip,bp1=0x003B61AB+0,action1=skip,bp2=0x003B61D2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 8B 85 F0 FE FF FF 85 C0 0F 84 33 FD FF FF }
        $pattern2 = { BA 21 05 00 00 53 6A 40 53 68 40 11 3B 00 }

    condition:
        any of them
}