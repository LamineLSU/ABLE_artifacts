rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF C1 ?? ?? }
        $pattern1 = { 4D C9 FF 5A ?? ?? }
        $pattern2 = { FE F7 FF 3F ?? ?? }

    condition:
        any of them
}