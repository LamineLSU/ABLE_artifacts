rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - TEST EAX followed by JE, unusual instruction sequence"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 85 C0 EA EA 74 12 01 0E 61 90 }
        $pattern1 = { 20 FF EE CE 03 C3 AD EA EB 5A ED }
        $pattern2 = { 20 FF EE CE 8B E5 EB CC }

    condition:
        any of them
}