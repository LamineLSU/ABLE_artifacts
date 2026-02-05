rule Conditional_Jump_1
{
    meta:
        description = "Detects a conditional jump that may skip to exit process"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 83 F8 01 74 20 64 A1 ?? ?? ?? ?? }
    condition:
        $a
}

rule Conditional_Jump_2
{
    meta:
        description = "Detects a conditional jump that may skip to exit process"
    strings:
        $b = { A8 01 75 10 FF 75 08 }
    condition:
        $b
}

rule TerminateProcess_Call
{
    meta:
        description = "Detects a call to TerminateProcess which may prevent exit"
    strings:
        $c = { 50 FF 15 ?? ?? ?? ?? }
    condition:
        $c
}