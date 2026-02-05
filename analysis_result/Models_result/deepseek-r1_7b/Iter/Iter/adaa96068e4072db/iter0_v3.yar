rule EvasionBypass
{
    meta:
        description = "Evasion bypass patterns targeting TEST instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 8B 45 14 8B 06 83 C4 14 FF D0 ?? } 
        $pattern1 = { 5A 6A ?? 5A 8B CE E8 ?? } 
        $pattern2 = { 4F 01 85 C0 0F 84 ?? ?? ?? } 

    condition:
        any of them
}