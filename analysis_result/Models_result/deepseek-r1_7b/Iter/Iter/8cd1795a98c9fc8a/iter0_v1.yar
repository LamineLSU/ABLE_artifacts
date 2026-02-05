rule Bypass_Evasion
{
    meta:
        description = "Bypasses function calls in memory access instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E9 ?? 0x8F7250 ?? ? }
        $pattern1 = { E8 ?? ?? ?? ?? ?? }
        $pattern2 = { je ?? 0x8F7250 ?? ? }
}