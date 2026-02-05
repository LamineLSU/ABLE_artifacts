rule Malicious_Control_Flow
{
    meta:
        description = "Detects evasion checks and termination logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-20"

    strings:
        $a = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $b = { C1 E8 08 A8 01 75 10 }
        $c = { 50 FF 15 40 F1 42 00 }

    condition:
        all of ($a or $b or $c)
}