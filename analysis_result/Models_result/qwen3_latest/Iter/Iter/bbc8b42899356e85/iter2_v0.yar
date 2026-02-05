rule ExampleRule
{
    meta:
        description = "Detects specific test and jump patterns and a call to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-10"

    strings:
        // First test, je, and mov sequence
        $a = { 85 C0 74 12 8B 45 FC }

        // First JE instruction (0F 84) with wildcards
        $b = { 0F 84 ?? ?? ?? ?? }

        // Second test, je, and mov sequence
        $c = { 85 C0 74 12 8B 4D F8 }

    condition:
        $a or $b or $c
}