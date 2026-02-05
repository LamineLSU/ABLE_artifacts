rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF 55 8B EC FF 75 08 }
        $pattern1 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}