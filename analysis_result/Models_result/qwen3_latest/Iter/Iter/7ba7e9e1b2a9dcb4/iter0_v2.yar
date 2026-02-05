rule ExampleRule
{
    meta:
        description = "Example rule with three distinct patterns"
    
    strings:
        $a = {53} {FF15} {??} {??} {??} {??} {33FF}
        $b = {50} {FF15} {??} {??} {??} {??} {53}
        $c = {83C404} {FF15} {??} {??} {??} {??}
    
    condition:
        all of them
}