rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 }
        $pattern1 = { 5E 5D C3 6B 31 C1 19 E6 }

    condition:
        any of them
}