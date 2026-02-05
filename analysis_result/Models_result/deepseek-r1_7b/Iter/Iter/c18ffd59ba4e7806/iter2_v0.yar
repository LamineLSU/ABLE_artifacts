rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5E DE 7F CF E3 BF B9 0C 6A }
        $pattern1 = { FF C4 00 0C 8B 45 8D 81 8A F3 9D 9D 98 E3 BF }
        $pattern2 = { DD C5 07 8B 4F 65 0E 8B EC D8 7B DC }

    condition:
        any of them
}