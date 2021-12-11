package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	kyberk2so "github.com/symbolicsoft/kyber-k2so"
)

func main() {

	MASTER_KEY := [32]byte{48, 124, 87, 188, 181, 244, 165, 54, 249, 79, 112, 76, 201, 137, 208, 20, 14, 79, 102, 56, 19, 51, 125, 166, 52, 49, 19, 37, 194, 15, 99, 168}
	SECRET_KEY := [2400]byte{92, 85, 89, 83, 164, 33, 81, 24, 181, 217, 12, 101, 197, 36, 31, 169, 90, 186, 191, 156, 166, 111, 18, 26, 31, 99, 130, 101, 177, 166, 14,
		98, 62, 219, 123, 198, 59, 86, 105, 244, 12, 138, 114, 21, 130, 71, 244, 204, 48, 203, 51, 187, 243, 41, 154, 50, 28, 146, 134, 153, 53, 10, 19, 0, 26, 86, 86,
		134, 82, 55, 153, 147, 56, 161, 31, 247, 70, 44, 81, 71, 131, 5, 214, 111, 237, 245, 1, 59, 116, 163, 192, 104, 74, 18, 44, 123, 48, 218, 106, 145, 233, 5, 233,
		57, 18, 85, 234, 98, 37, 151, 150, 147, 193, 160, 147, 166, 204, 139, 105, 118, 249, 154, 174, 98, 41, 88, 130, 59, 193, 110, 54, 110, 135, 160, 129, 61, 58, 115,
		137, 72, 127, 32, 195, 9, 28, 245, 127, 236, 86, 38, 74, 101, 48, 41, 54, 140, 168, 136, 6, 101, 97, 50, 254, 231, 128, 161, 72, 66, 42, 136, 52, 246, 19, 125, 22,
		132, 173, 214, 145, 52, 234, 202, 60, 70, 53, 159, 196, 208, 89, 109, 87, 28, 177, 162, 194, 67, 56, 38, 39, 247, 6, 24, 12, 167, 30, 204, 62, 72, 156, 136, 102,
		118, 90, 115, 166, 175, 72, 60, 177, 77, 35, 6, 168, 204, 97, 10, 85, 115, 42, 32, 183, 80, 213, 78, 247, 234, 27, 247, 162, 117, 147, 199, 90, 22, 72, 43, 229, 7,
		40, 251, 25, 127, 95, 42, 144, 164, 19, 138, 163, 236, 176, 24, 187, 191, 119, 236, 145, 67, 249, 31, 206, 187, 151, 100, 176, 33, 43, 76, 4, 241, 74, 156, 61, 177,
		0, 253, 210, 179, 136, 9, 114, 245, 120, 127, 161, 44, 72, 215, 0, 127, 81, 100, 179, 183, 20, 82, 123, 71, 163, 65, 147, 51, 228, 112, 60, 226, 150, 12, 100, 107,
		173, 83, 202, 135, 33, 148, 10, 69, 204, 25, 109, 70, 171, 201, 183, 112, 26, 182, 75, 214, 27, 10, 53, 44, 32, 82, 146, 106, 43, 51, 3, 212, 90, 135, 99, 147, 172,
		77, 215, 151, 150, 164, 151, 243, 172, 109, 115, 240, 127, 209, 220, 189, 9, 156, 190, 215, 5, 24, 151, 166, 22, 158, 71, 49, 186, 200, 177, 29, 80, 194, 84, 186,
		150, 164, 153, 99, 148, 247, 187, 48, 171, 203, 75, 85, 119, 0, 106, 114, 170, 246, 198, 221, 64, 69, 120, 37, 65, 197, 25, 143, 79, 156, 91, 193, 88, 101, 26, 119,
		143, 108, 135, 168, 87, 199, 162, 207, 70, 148, 252, 217, 157, 198, 56, 11, 123, 66, 81, 87, 27, 175, 80, 218, 37, 170, 139, 72, 174, 215, 82, 187, 80, 50, 90, 120,
		93, 247, 133, 21, 206, 240, 14, 151, 210, 180, 134, 176, 46, 81, 153, 10, 242, 128, 175, 3, 84, 50, 80, 134, 163, 113, 200, 150, 244, 74, 124, 42, 140, 205, 171, 106,
		196, 210, 147, 183, 7, 115, 184, 22, 194, 94, 252, 140, 187, 75, 7, 155, 149, 19, 94, 177, 81, 42, 120, 195, 107, 175, 132, 157, 237, 252, 30, 60, 74, 77, 133, 69,
		164, 102, 214, 103, 136, 220, 158, 174, 236, 133, 223, 1, 51, 76, 208, 136, 196, 194, 44, 103, 180, 125, 120, 107, 22, 68, 65, 42, 102, 233, 5, 219, 161, 30, 188, 3,
		125, 101, 70, 21, 96, 186, 137, 173, 145, 161, 255, 4, 0, 165, 149, 167, 216, 27, 39, 250, 177, 168, 18, 201, 175, 106, 106, 78, 244, 185, 129, 153, 226, 146, 195,
		188, 194, 26, 54, 33, 49, 97, 11, 188, 187, 109, 153, 57, 14, 180, 246, 134, 84, 72, 34, 234, 75, 81, 24, 165, 104, 221, 224, 170, 108, 76, 192, 1, 155, 2, 24, 138,
		112, 211, 198, 36, 233, 53, 106, 122, 6, 148, 187, 246, 84, 239, 68, 15, 15, 201, 207, 92, 104, 190, 6, 90, 136, 86, 7, 84, 4, 119, 202, 250, 86, 27, 179, 231, 126,
		36, 168, 139, 233, 234, 149, 234, 219, 5, 153, 128, 196, 115, 102, 48, 115, 86, 139, 34, 148, 108, 53, 242, 93, 129, 199, 123, 70, 171, 145, 189, 103, 83, 68, 227,
		48, 103, 57, 165, 218, 100, 189, 241, 247, 174, 33, 12, 38, 215, 176, 106, 39, 57, 74, 81, 138, 3, 251, 113, 100, 60, 195, 51, 169, 44, 158, 70, 65, 174, 71, 149,
		170, 187, 154, 8, 226, 164, 14, 146, 138, 85, 145, 26, 169, 236, 250, 79, 129, 180, 175, 196, 103, 165, 124, 19, 84, 17, 224, 50, 237, 242, 154, 171, 5, 121, 86,
		115, 47, 224, 2, 199, 8, 67, 173, 188, 230, 153, 252, 219, 46, 77, 119, 32, 106, 20, 100, 197, 67, 17, 245, 120, 90, 151, 112, 200, 202, 202, 93, 35, 241, 41, 29,
		170, 180, 130, 52, 61, 159, 135, 175, 76, 225, 129, 179, 71, 51, 249, 69, 72, 78, 249, 56, 220, 104, 21, 50, 108, 172, 151, 129, 202, 34, 169, 186, 209, 247, 54,
		87, 146, 154, 85, 220, 76, 219, 7, 205, 22, 10, 195, 251, 23, 198, 240, 27, 73, 28, 1, 185, 153, 60, 138, 254, 171, 11, 195, 0, 15, 49, 210, 125, 219, 243, 108, 0,
		113, 98, 112, 104, 104, 116, 226, 24, 119, 132, 111, 117, 165, 44, 180, 164, 188, 160, 154, 42, 217, 193, 196, 34, 73, 33, 20, 153, 175, 11, 42, 165, 69, 171, 110,
		135, 113, 145, 154, 59, 174, 117, 149, 150, 54, 147, 49, 104, 194, 85, 140, 87, 111, 73, 178, 192, 10, 128, 59, 58, 176, 29, 82, 228, 77, 213, 247, 151, 164, 97, 189,
		213, 227, 67, 210, 169, 59, 151, 204, 135, 68, 102, 126, 158, 218, 173, 54, 171, 13, 26, 178, 156, 170, 194, 9, 187, 71, 28, 135, 166, 126, 234, 41, 103, 92, 21, 49,
		177, 48, 70, 89, 36, 63, 140, 181, 166, 220, 234, 73, 50, 35, 140, 29, 215, 168, 55, 139, 149, 187, 211, 9, 144, 227, 29, 57, 178, 158, 152, 232, 6, 52, 140, 126, 159,
		101, 24, 85, 196, 6, 213, 28, 47, 68, 129, 206, 33, 82, 85, 191, 16, 65, 0, 48, 88, 167, 236, 11, 166, 23, 195, 102, 21, 33, 193, 178, 83, 183, 129, 25, 102, 244, 123,
		226, 24, 171, 218, 232, 45, 88, 6, 57, 222, 60, 88, 204, 244, 114, 249, 58, 87, 229, 153, 147, 254, 57, 15, 91, 9, 29, 170, 145, 98, 230, 106, 162, 32, 186, 3, 206, 44,
		143, 150, 119, 121, 75, 193, 64, 100, 245, 35, 132, 92, 8, 113, 145, 194, 66, 64, 110, 77, 35, 179, 109, 114, 54, 133, 203, 162, 252, 55, 83, 36, 183, 54, 113, 117, 148,
		132, 21, 195, 48, 252, 196, 151, 165, 190, 179, 105, 142, 0, 59, 41, 3, 85, 153, 3, 35, 194, 71, 161, 40, 162, 196, 136, 96, 252, 166, 0, 151, 0, 133, 35, 62, 161, 135,
		23, 242, 204, 35, 151, 52, 153, 251, 42, 195, 130, 34, 85, 243, 71, 135, 184, 91, 149, 190, 0, 149, 30, 0, 193, 129, 2, 61, 100, 73, 101, 106, 54, 6, 95, 53, 60, 189, 40,
		94, 135, 39, 33, 113, 23, 126, 243, 137, 205, 219, 108, 109, 78, 114, 142, 224, 150, 53, 210, 118, 23, 133, 32, 110, 120, 204, 149, 68, 58, 189, 122, 234, 129, 207, 114,
		105, 255, 117, 200, 77, 41, 155, 94, 108, 206, 38, 240, 148, 99, 155, 65, 150, 249, 172, 168, 171, 23, 56, 200, 129, 65, 188, 38, 251, 55, 14, 195, 86, 107, 83, 229, 174,
		6, 131, 143, 181, 64, 134, 57, 224, 83, 136, 138, 166, 180, 70, 94, 145, 56, 52, 95, 83, 10, 174, 113, 37, 174, 170, 27, 6, 44, 107, 138, 34, 4, 62, 128, 143, 99, 149, 144,
		167, 151, 177, 178, 128, 56, 19, 168, 112, 185, 200, 9, 185, 177, 30, 235, 140, 120, 170, 211, 141, 95, 92, 194, 57, 23, 13, 69, 40, 125, 221, 156, 183, 206, 138, 10, 108,
		34, 61, 102, 187, 201, 159, 54, 167, 48, 236, 118, 93, 132, 202, 114, 129, 126, 5, 8, 62, 105, 56, 114, 210, 35, 120, 190, 185, 89, 61, 117, 93, 248, 150, 176, 114, 92, 110,
		70, 204, 41, 149, 138, 87, 59, 203, 75, 181, 4, 83, 59, 160, 142, 192, 92, 183, 203, 112, 59, 101, 204, 158, 212, 108, 100, 182, 33, 158, 227, 135, 174, 162, 233, 82, 224,
		8, 106, 176, 186, 137, 164, 236, 85, 202, 224, 29, 105, 224, 160, 208, 7, 179, 104, 247, 21, 80, 106, 45, 183, 128, 98, 30, 124, 34, 112, 199, 73, 187, 19, 40, 211, 108,
		39, 172, 235, 207, 209, 119, 77, 202, 53, 9, 153, 181, 66, 57, 32, 171, 166, 32, 122, 163, 208, 156, 215, 24, 128, 5, 99, 156, 32, 5, 183, 191, 81, 41, 173, 164, 170, 139,
		129, 178, 188, 19, 29, 150, 7, 89, 248, 117, 88, 247, 87, 176, 193, 196, 104, 162, 25, 207, 90, 105, 97, 85, 204, 191, 16, 195, 97, 215, 36, 196, 252, 37, 138, 160, 196,
		137, 140, 138, 36, 81, 56, 31, 49, 180, 123, 207, 40, 175, 40, 58, 125, 88, 36, 32, 243, 197, 100, 139, 92, 30, 155, 202, 109, 22, 1, 42, 52, 116, 155, 169, 166, 61, 41,
		25, 187, 123, 181, 13, 216, 105, 159, 126, 113, 191, 71, 41, 181, 253, 105, 187, 147, 117, 124, 254, 193, 138, 122, 235, 13, 3, 152, 125, 60, 251, 109, 131, 168, 70, 199,
		42, 86, 156, 177, 64, 0, 61, 22, 88, 240, 48, 88, 91, 122, 200, 1, 32, 164, 36, 74, 141, 49, 53, 94, 11, 14, 33, 41, 124, 228, 9, 136, 160, 203, 11, 238, 59, 186, 8, 195,
		82, 169, 176, 170, 154, 233, 82, 254, 10, 192, 148, 233, 128, 225, 201, 43, 79, 248, 43, 69, 156, 95, 113, 70, 95, 157, 11, 173, 230, 107, 176, 138, 107, 168, 174, 160,
		139, 30, 135, 87, 157, 112, 204, 102, 66, 102, 233, 234, 6, 110, 107, 143, 42, 139, 140, 236, 21, 130, 240, 119, 78, 113, 220, 66, 57, 133, 66, 241, 218, 103, 128, 204,
		32, 109, 246, 92, 185, 22, 181, 232, 226, 181, 74, 80, 48, 35, 229, 94, 20, 151, 99, 46, 240, 58, 49, 21, 138, 14, 98, 142, 119, 228, 112, 86, 163, 122, 24, 137, 125, 155,
		134, 89, 38, 183, 84, 160, 148, 42, 227, 34, 125, 196, 8, 192, 136, 215, 49, 107, 172, 22, 56, 224, 98, 234, 169, 14, 65, 203, 100, 63, 80, 105, 206, 72, 42, 61, 165, 160,
		179, 103, 59, 162, 67, 99, 225, 71, 149, 128, 179, 158, 193, 151, 201, 255, 245, 62, 124, 177, 203, 247, 16, 154, 37, 166, 140, 42, 170, 19, 9, 90, 61, 212, 92, 62, 143,
		197, 192, 175, 98, 155, 150, 19, 14, 15, 129, 79, 49, 35, 30, 1, 193, 98, 15, 129, 182, 93, 71, 158, 104, 4, 128, 64, 231, 91, 26, 199, 103, 150, 178, 2, 138, 232, 52, 213,
		203, 178, 10, 101, 84, 189, 242, 68, 144, 113, 34, 242, 225, 136, 173, 131, 7, 86, 86, 45, 49, 65, 189, 229, 172, 143, 104, 183, 122, 21, 2, 41, 60, 67, 61, 174, 55, 127,
		219, 249, 153, 244, 129, 177, 45, 225, 100, 132, 65, 21, 115, 140, 164, 88, 96, 22, 187, 250, 10, 244, 41, 75, 62, 170, 78, 202, 34, 4, 70, 22, 158, 145, 104, 3, 69, 183,
		133, 193, 48, 150, 63, 60, 25, 128, 170, 162, 203, 202, 107, 196, 176, 67, 247, 156, 130, 93, 134, 184, 64, 76, 60, 168, 211, 171, 126, 112, 144, 66, 217, 196, 174, 56,
		192, 107, 90, 80, 26, 140, 70, 57, 181, 199, 107, 128, 138, 95, 115, 59, 13, 34, 34, 219, 70, 185, 180, 12, 21, 117, 21, 129, 204, 220, 87, 50, 26, 171, 188, 70, 188, 136,
		182, 22, 113, 203, 2, 213, 89, 87, 251, 25, 192, 115, 70, 126, 45, 216, 77, 197, 38, 74, 155, 19, 65, 178, 155, 145, 119, 162, 5, 98, 34, 30, 55, 209, 44, 94, 2, 14, 75,
		96, 200, 129, 19, 142, 251, 197, 25, 169, 100, 141, 27, 140, 121, 126, 201, 156, 154, 97, 29, 76, 83, 119, 201, 236, 126, 19, 37, 44, 97, 121, 56, 146, 103, 189, 69, 170,
		127, 65, 2, 193, 12, 81, 36, 98, 90, 88, 179, 89, 149, 239, 88, 21, 22, 162, 134, 196, 140, 173, 130, 182, 180, 199, 231, 162, 156, 243, 156, 15, 16, 199, 105, 179, 49, 93,
		113, 15, 46, 129, 202, 148, 53, 133, 133, 64, 190, 119, 136, 40, 245, 192, 16, 219, 112, 191, 243, 64, 166, 69, 59, 187, 94, 112, 147, 125, 180, 188, 10, 240, 105, 186, 9,
		27, 230, 131, 201, 52, 161, 172, 197, 0, 118, 43, 123, 132, 166, 225, 205, 115, 25, 104, 80, 69, 171, 146, 213, 27, 118, 147, 18, 44, 112, 32, 180, 10, 134, 61, 186, 104,
		58, 251, 19, 233, 231, 93, 223, 11, 157, 187, 122, 80, 129, 84, 207, 74, 171, 143, 205, 250, 184, 95, 236, 181, 190, 7, 155, 13, 21, 154, 70, 203, 16, 157, 144, 9, 31, 72,
		83, 240, 216, 36, 58, 130, 140, 146, 178, 168, 199, 178, 95, 121, 187, 95, 158, 165, 155, 88, 220, 95, 124, 163, 112, 44, 85, 65, 177, 208, 117, 56, 83, 92, 178, 212, 62,
		135, 84, 118, 55, 39, 67, 126, 213, 112, 79, 104, 184, 239, 22, 152, 53, 234, 39, 64, 232, 199, 193, 121, 63, 198, 181, 153, 119, 182, 190, 195, 234, 17, 28, 4, 24, 70, 3,
		118, 73, 41, 167, 254, 85, 204, 26, 251, 165, 143, 38, 212, 253, 169, 209, 217, 140, 104, 95, 70, 177, 9, 44, 232, 173, 211, 154, 160, 116, 159, 25, 48, 70, 47, 218, 169,
		70, 60, 162, 145, 150, 85, 145, 184, 61}
	/*
		PUBLIC_KEY := [1184]byte{132, 21, 195, 48, 252, 196, 151, 165, 190, 179, 105, 142, 0, 59, 41, 3, 85, 153, 3, 35, 194, 71, 161, 40, 162, 196, 136, 96, 252, 166, 0, 151, 0, 133,
			35, 62, 161, 135, 23, 242, 204, 35, 151, 52, 153, 251, 42, 195, 130, 34, 85, 243, 71, 135, 184, 91, 149, 190, 0, 149, 30, 0, 193, 129, 2, 61, 100, 73, 101, 106, 54, 6, 95,
			53, 60, 189, 40, 94, 135, 39, 33, 113, 23, 126, 243, 137, 205, 219, 108, 109, 78, 114, 142, 224, 150, 53, 210, 118, 23, 133, 32, 110, 120, 204, 149, 68, 58, 189, 122, 234,
			129, 207, 114, 105, 255, 117, 200, 77, 41, 155, 94, 108, 206, 38, 240, 148, 99, 155, 65, 150, 249, 172, 168, 171, 23, 56, 200, 129, 65, 188, 38, 251, 55, 14, 195, 86, 107,
			83, 229, 174, 6, 131, 143, 181, 64, 134, 57, 224, 83, 136, 138, 166, 180, 70, 94, 145, 56, 52, 95, 83, 10, 174, 113, 37, 174, 170, 27, 6, 44, 107, 138, 34, 4, 62, 128, 143,
			99, 149, 144, 167, 151, 177, 178, 128, 56, 19, 168, 112, 185, 200, 9, 185, 177, 30, 235, 140, 120, 170, 211, 141, 95, 92, 194, 57, 23, 13, 69, 40, 125, 221, 156, 183, 206,
			138, 10, 108, 34, 61, 102, 187, 201, 159, 54, 167, 48, 236, 118, 93, 132, 202, 114, 129, 126, 5, 8, 62, 105, 56, 114, 210, 35, 120, 190, 185, 89, 61, 117, 93, 248, 150, 176,
			114, 92, 110, 70, 204, 41, 149, 138, 87, 59, 203, 75, 181, 4, 83, 59, 160, 142, 192, 92, 183, 203, 112, 59, 101, 204, 158, 212, 108, 100, 182, 33, 158, 227, 135, 174, 162,
			233, 82, 224, 8, 106, 176, 186, 137, 164, 236, 85, 202, 224, 29, 105, 224, 160, 208, 7, 179, 104, 247, 21, 80, 106, 45, 183, 128, 98, 30, 124, 34, 112, 199, 73, 187, 19, 40,
			211, 108, 39, 172, 235, 207, 209, 119, 77, 202, 53, 9, 153, 181, 66, 57, 32, 171, 166, 32, 122, 163, 208, 156, 215, 24, 128, 5, 99, 156, 32, 5, 183, 191, 81, 41, 173, 164,
			170, 139, 129, 178, 188, 19, 29, 150, 7, 89, 248, 117, 88, 247, 87, 176, 193, 196, 104, 162, 25, 207, 90, 105, 97, 85, 204, 191, 16, 195, 97, 215, 36, 196, 252, 37, 138, 160,
			196, 137, 140, 138, 36, 81, 56, 31, 49, 180, 123, 207, 40, 175, 40, 58, 125, 88, 36, 32, 243, 197, 100, 139, 92, 30, 155, 202, 109, 22, 1, 42, 52, 116, 155, 169, 166, 61, 41,
			25, 187, 123, 181, 13, 216, 105, 159, 126, 113, 191, 71, 41, 181, 253, 105, 187, 147, 117, 124, 254, 193, 138, 122, 235, 13, 3, 152, 125, 60, 251, 109, 131, 168, 70, 199, 42,
			86, 156, 177, 64, 0, 61, 22, 88, 240, 48, 88, 91, 122, 200, 1, 32, 164, 36, 74, 141, 49, 53, 94, 11, 14, 33, 41, 124, 228, 9, 136, 160, 203, 11, 238, 59, 186, 8, 195, 82, 169,
			176, 170, 154, 233, 82, 254, 10, 192, 148, 233, 128, 225, 201, 43, 79, 248, 43, 69, 156, 95, 113, 70, 95, 157, 11, 173, 230, 107, 176, 138, 107, 168, 174, 160, 139, 30, 135,
			87, 157, 112, 204, 102, 66, 102, 233, 234, 6, 110, 107, 143, 42, 139, 140, 236, 21, 130, 240, 119, 78, 113, 220, 66, 57, 133, 66, 241, 218, 103, 128, 204, 32, 109, 246, 92,
			185, 22, 181, 232, 226, 181, 74, 80, 48, 35, 229, 94, 20, 151, 99, 46, 240, 58, 49, 21, 138, 14, 98, 142, 119, 228, 112, 86, 163, 122, 24, 137, 125, 155, 134, 89, 38, 183,
			84, 160, 148, 42, 227, 34, 125, 196, 8, 192, 136, 215, 49, 107, 172, 22, 56, 224, 98, 234, 169, 14, 65, 203, 100, 63, 80, 105, 206, 72, 42, 61, 165, 160, 179, 103, 59, 162,
			67, 99, 225, 71, 149, 128, 179, 158, 193, 151, 201, 255, 245, 62, 124, 177, 203, 247, 16, 154, 37, 166, 140, 42, 170, 19, 9, 90, 61, 212, 92, 62, 143, 197, 192, 175, 98, 155,
			150, 19, 14, 15, 129, 79, 49, 35, 30, 1, 193, 98, 15, 129, 182, 93, 71, 158, 104, 4, 128, 64, 231, 91, 26, 199, 103, 150, 178, 2, 138, 232, 52, 213, 203, 178, 10, 101, 84,
			189, 242, 68, 144, 113, 34, 242, 225, 136, 173, 131, 7, 86, 86, 45, 49, 65, 189, 229, 172, 143, 104, 183, 122, 21, 2, 41, 60, 67, 61, 174, 55, 127, 219, 249, 153, 244, 129,
			177, 45, 225, 100, 132, 65, 21, 115, 140, 164, 88, 96, 22, 187, 250, 10, 244, 41, 75, 62, 170, 78, 202, 34, 4, 70, 22, 158, 145, 104, 3, 69, 183, 133, 193, 48, 150, 63, 60,
			25, 128, 170, 162, 203, 202, 107, 196, 176, 67, 247, 156, 130, 93, 134, 184, 64, 76, 60, 168, 211, 171, 126, 112, 144, 66, 217, 196, 174, 56, 192, 107, 90, 80, 26, 140, 70,
			57, 181, 199, 107, 128, 138, 95, 115, 59, 13, 34, 34, 219, 70, 185, 180, 12, 21, 117, 21, 129, 204, 220, 87, 50, 26, 171, 188, 70, 188, 136, 182, 22, 113, 203, 2, 213, 89,
			87, 251, 25, 192, 115, 70, 126, 45, 216, 77, 197, 38, 74, 155, 19, 65, 178, 155, 145, 119, 162, 5, 98, 34, 30, 55, 209, 44, 94, 2, 14, 75, 96, 200, 129, 19, 142, 251, 197,
			25, 169, 100, 141, 27, 140, 121, 126, 201, 156, 154, 97, 29, 76, 83, 119, 201, 236, 126, 19, 37, 44, 97, 121, 56, 146, 103, 189, 69, 170, 127, 65, 2, 193, 12, 81, 36, 98,
			90, 88, 179, 89, 149, 239, 88, 21, 22, 162, 134, 196, 140, 173, 130, 182, 180, 199, 231, 162, 156, 243, 156, 15, 16, 199, 105, 179, 49, 93, 113, 15, 46, 129, 202, 148, 53,
			133, 133, 64, 190, 119, 136, 40, 245, 192, 16, 219, 112, 191, 243, 64, 166, 69, 59, 187, 94, 112, 147, 125, 180, 188, 10, 240, 105, 186, 9, 27, 230, 131, 201, 52, 161, 172,
			197, 0, 118, 43, 123, 132, 166, 225, 205, 115, 25, 104, 80, 69, 171, 146, 213, 27, 118, 147, 18, 44, 112, 32, 180, 10, 134, 61, 186, 104, 58, 251, 19, 233, 231, 93, 223, 11,
			157, 187, 122, 80, 129, 84, 207, 74, 171, 143, 205, 250, 184, 95, 236, 181, 190, 7, 155, 13, 21, 154, 70, 203, 16, 157, 144, 9, 31, 72, 83, 240, 216, 36, 58, 130, 140, 146,
			178, 168, 199, 178, 95, 121, 187, 95, 158, 165, 155, 88, 220, 95, 124, 163, 112, 44, 85, 65, 177, 208, 117, 56, 83, 92, 178, 212, 62, 135, 84, 118, 55, 39, 67, 126, 213, 112,
			79, 104, 184, 239, 22, 152, 53, 234, 39, 64, 232}
	*/
	//========================================================================================//
	// SERVER SIDE PROTOCOL TEST 2
	//========================================================================================//
	// open plaintext data file and read into byte array
	PLAINTEXT, err := ioutil.ReadFile("../data/plaintext.txt")
	if err != nil {
		fmt.Print(err)
	}
	// encrypt plaintext data with master key
	CIPHERTEXT := AES256GCM_ENCRYPT(MASTER_KEY, PLAINTEXT)
	// save ciphertext data to file as base64 string
	outfile, err := os.Create("../data/ciphertext.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	// bytes to base64
	CIPHERTEXT_base64 := base64.StdEncoding.EncodeToString(CIPHERTEXT)
	_, err1 := outfile.WriteString(CIPHERTEXT_base64)
	if err1 != nil {
		log.Fatal(err1)
	}
	//========================================================================================//
	// STEP 2: SESSION KEY DECAPSULATION
	//========================================================================================//
	// read c values from client into array
	c_base64_array := make([]string, 0)
	// open client_c.txt file
	file, err := os.Open("../data/client_c.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// read base64 strings into array
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		c_base64 := scanner.Text()
		c_base64_array = append(c_base64_array, c_base64)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// for each c value from client (100 values)
	time_sum2 := 0
	SESSION_KEY_base64_array := make([]string, 0)
	for i := 0; i < 100; i++ { // average of 100 test runs

		// start timer
		start := time.Now()

		//-------------------------------------------------------
		// get c from c_base64_array and convert to byte array
		c_byte, _ := base64.StdEncoding.DecodeString(c_base64_array[i])
		var c [1088]byte
		copy(c[:], c_byte)
		// 2. (Session) Key Decapsulation
		SESSION_KEY, _ := kyberk2so.KemDecrypt768(c, SECRET_KEY)
		// convert session key to base64 string
		SESSION_KEY_base64 := base64.StdEncoding.EncodeToString(SESSION_KEY[:])
		//-------------------------------------------------------

		// end timer
		time2 := time.Since(start)

		// add to time sum
		time_sum2 += int(time2.Microseconds()) // convert to microseconds

		// append to array
		SESSION_KEY_base64_array = append(SESSION_KEY_base64_array, SESSION_KEY_base64)
	}
	// calculate average time for step 2
	avg_time2 := float64(time_sum2) / 100.0
	fmt.Println("Average time step 2: ", avg_time2, " microseconds")

	// write session keys to server_ss.txt
	outfile2, err := os.Create("../data/server_ss.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile2.Close()
	// write to file
	for i := 0; i < 100; i++ {
		_, err1 := outfile2.WriteString(SESSION_KEY_base64_array[i] + "\n")
		if err1 != nil {
			log.Fatal(err1)
		}
	}

	time_sum3 := 0
	ENC_MASTER_KEY_base64_array := make([]string, 0)
	for i := 0; i < 100; i++ { // average of 100 test runs

		// start timer
		start := time.Now()

		//-------------------------------------------------------
		// decode session key into byte array
		SESSION_KEY_byte, _ := base64.StdEncoding.DecodeString(SESSION_KEY_base64_array[i])
		var SESSION_KEY [32]byte
		copy(SESSION_KEY[:], SESSION_KEY_byte)
		// 3. Encrypt MASTER_KEY with SESSION_KEY
		ENC_MASTER_KEY := AES256GCM_ENCRYPT(SESSION_KEY, MASTER_KEY[:])
		// convert ENC_MASTER_KEY to base64 string and append to array
		ENC_MASTER_KEY_base64 := base64.StdEncoding.EncodeToString(ENC_MASTER_KEY[:])
		//-------------------------------------------------------

		// end timer
		time3 := time.Since(start)

		// add to time sum
		time_sum3 += int(time3.Microseconds()) // convert to microseconds

		// append to array
		ENC_MASTER_KEY_base64_array = append(ENC_MASTER_KEY_base64_array, ENC_MASTER_KEY_base64)
	}
	// calculate average time for step 3
	avg_time3 := float64(time_sum3) / 100.0
	fmt.Println("Average time step 3: ", avg_time3, " microseconds")

	// add to text file (for client side testing)
	// open server_enc_mk.txt file
	file1, err1 := os.Create("../data/server_enc_mk.txt")
	if err1 != nil {
		log.Fatal(err1)
	}
	defer file1.Close()
	// write to file
	for i := 0; i < 100; i++ {
		_, err1 := file1.WriteString(ENC_MASTER_KEY_base64_array[i] + "\n")
		if err1 != nil {
			log.Fatal(err1)
		}
	}

}

// bytes as input and output
func AES256GCM_ENCRYPT(KEY [32]byte, PLAINTEXT []byte) []byte {

	block, err := aes.NewCipher(KEY[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}
	CIPHERTEXT := gcm.Seal(nonce, nonce, []byte(PLAINTEXT), nil)

	return CIPHERTEXT
}
