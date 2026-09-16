// Package dbrevocation porte le stockage des ordres de révocation (kill switch).
//
// Un ordre est DURABLE, pas un message éphémère. Il est écrit ici avec la liste
// des machines qu'il vise, poussé aux machines connectées, puis rejoué tant
// qu'il n'est pas acquitté. Sans cette persistance, éteindre son poste
// suffirait à échapper à une révocation — précisément le cas où elle compte.
package dbrevocation
