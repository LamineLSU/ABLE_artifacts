rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targets early EAX checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B C9 6C 43 F7 ?? }  // EAX test before call
        $pattern1 = { FF FF FF FF FF FE DD FF FE FF }  // Conditional call pattern near exit
        $pattern2 = { 8B 4D FC C9 5E 02 4C 36 ?? }  // Specific instruction sequence to bypass
    condition:
        any of them
}