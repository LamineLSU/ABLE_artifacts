rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting different steps of the evasion chain"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? ?? FF 75 08 EB ?? ?? ?? FF C8 FF FF FF CA ?? }
        $pattern1 = { 55 ?? 8B EC ?? FF 75 08 DD EB 08 ?? ?? FF C8 FF FF FF CA ?? }
        $pattern2 = { ?? ?? E8 C8 FF FF FF CA ?? ?? ?? FF C8 FF FF FF CA ?? }
    condition:
        any of them
}