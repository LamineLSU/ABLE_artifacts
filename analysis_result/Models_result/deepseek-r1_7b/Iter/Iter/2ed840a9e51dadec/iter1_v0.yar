rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 85 C0 74 12 ?? }
        $pattern1 = { 20 FF EE CE 85 C0 74 12 ?? E8 CE 5A }
        $pattern2 = { 20 FF EE CE 85 C0 E8 CE 5A E8 A1 2C }

    condition:
        any of them
}