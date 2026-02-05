rule EvasionCheck
{
    meta:
        description = "Detects evasion logic in the target binary"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-10"

    strings:
        $pattern0 = { E8 CD 3D 00 00 83 F8 01 74 20 } // Call to check function + cmp/je
        $pattern1 = { A8 01 75 10 }                     // Test al + jne
        $pattern2 = { E8 3A 30 1C 04 90 }               // Call to 04EC023Fh + nop

    condition:
        all of them
}