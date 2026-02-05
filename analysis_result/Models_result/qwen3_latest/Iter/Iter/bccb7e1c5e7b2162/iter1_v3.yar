rule ConditionalBranchPattern
{
    meta:
        description = "Identifies conditional branch patterns involving zero tests and jumps."
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $pattern1 = { 8B 45 08 85 C0 74 12 }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern3 = { E8 25 05 00 00 85 C0 74 12 }

    condition:
        all of them
}