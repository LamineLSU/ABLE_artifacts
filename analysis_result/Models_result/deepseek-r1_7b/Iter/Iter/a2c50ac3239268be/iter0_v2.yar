rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting key conditional calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 03 8B F0 }  # Skipping two mov instructions
        $pattern1 = { E8 70 FE FFFF }  # Skipping an earlier call
        $pattern2 = { E8 FB DCFFFF }   # Skipping the final exit call
    condition:
        any of them
}