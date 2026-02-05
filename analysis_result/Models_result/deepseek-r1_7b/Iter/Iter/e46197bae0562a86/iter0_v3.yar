rule Bypass_Evasion
{
    meta:
        description = "Memory bypass patterns for sandbox evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D FF 75 ?? FF 75 FF 0F ?? ?? }
        
        $pattern1 = { 6A 40 53 ?? E8 C8 ?? ?? ?? }

        $pattern2 = { 03 C3 8B EC ?? FF 75 ?? ?? }
        
    condition:
        any_of_them
}