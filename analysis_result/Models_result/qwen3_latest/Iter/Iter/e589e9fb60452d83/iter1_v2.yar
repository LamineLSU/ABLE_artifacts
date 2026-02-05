rule ConditionalBehavior
{
    meta:
        description = "Detects conditional logic with bit manipulation and API calls"
        cape_options = "bp0=$cond+0,action0=skip,bp1=$bit+0,action1=skip,bp2=$term+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $cond = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $bit = { C1 E8 08 A8 01 75 10 }
        $term = { FF 15 20 A2 46 00 }

    condition:
        all of them
}