rule Bypass_Sample
{
    meta:
        description = "Evasion bypass by TEST EAX, JZ, or call at specific addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 40 E7 C3 ?? ?? ?? ?? 8B FF }+0,action=skip
        $pattern1 = { 00 40 E7 C3 ?? ?? ?? ?? ?? ?? }+1,action=skip
        $pattern2 = { 00 40 E7 C3 ?? ?? ?? ?? E8 C8 FF FF FF }+1,action=skip

    condition:
        any of them
}