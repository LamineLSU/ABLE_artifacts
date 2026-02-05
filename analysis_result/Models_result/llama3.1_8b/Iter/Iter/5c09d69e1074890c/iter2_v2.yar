rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 ?? ?? ?? }
        $pattern1 = { 52 5E 5D C3 ?? ?? ?? ?? }
        $pattern2 = { EF 97 0D D1 C1 55 8B ?? ?? ?? }

    condition:
        any of them
}