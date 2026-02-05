rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E 8B 45 FC }
        $pattern1 = { E8 EE 82 FF FF 74 0E 8B 4F F8 }

    condition:
        any of them
}