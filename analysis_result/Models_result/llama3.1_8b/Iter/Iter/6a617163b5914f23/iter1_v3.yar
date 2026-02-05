rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern0+5,action1=skip,bp2=$pattern0+10,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 83 F9 FF FF FF C3 }

    condition:
        any of them
}