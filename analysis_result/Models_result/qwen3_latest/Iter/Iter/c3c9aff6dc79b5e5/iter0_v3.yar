rule IsWindowVisibleCheck
{
    meta:
        description = "Detects the IsWindowVisible check that may indicate analysis environment"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? }  // Call to IsWindowVisible
        $b = { 85 C0 }            // Test EAX, EAX
        $c = { 0F 84 ?? ?? ?? ?? } // JE instruction (jump if zero)
    condition:
        $a and $b and $c
}