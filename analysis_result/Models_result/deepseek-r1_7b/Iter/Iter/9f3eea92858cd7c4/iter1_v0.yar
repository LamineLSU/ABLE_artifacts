rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? FF FC }
        $pattern1 = { 8B 45 FC ?? 3F 8C ?? }
        $pattern2 = { 8D 43 01 EA EA EB 04 5F ED }
    condition:
        any of them
}