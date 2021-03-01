# Hasher

A .NET hashing library for easy and simple use.

## How Hasher Works?

This Hasher extension is a simple tool to hash your strings while you can control the properties of the hash. Within the Hasher extension there are two classes:

### The `Salt` class

The Salt class is for generating an unique Salt. When using this class you need to pass the minimum & maximum length. The purpose of this class is to have control over the size of the Salt, instead of the methods itself.

### The `Hasher` class

This class contains functionalities for three hashing algorithms:

* ***Sha256:*** *more information about the algorithm [here](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256?view=net-5.0).*
* ***Sha512:*** *more information about the algorithm [here](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512?view=net-5.0).*
* ***PBKDF2:*** *more information about the algorithm [here](https://en.wikipedia.org/wiki/PBKDF2).*

Every algorithm has his own **Compute** & **Validate** method. 

## How Do I Use Hasher?

This extension is created for easier and simpler use, so everything is very straight forward. Within the **Examples** directory, you can find demo's of the three hashing algorithms, together with the salt generation.

The classes are `sealed`, this means the classes are not meant for inheritance. When you really want to use with inheritance, just delete the `sealed` keyword.

The extension is XML Documented, so it's supported with C# intellisense.

## Requirements

There are no third party libraries used in this extension, only .NET libraries.

## Installation.

This extension is installed through Git.

1. Clone the repository: `git clone https://github.com/mHvNG/Hasher`
2. Move the `Hasher.cs` to your own project .NET project.
3. Open the file with your texteditor.
4. Change the namespace to: `[yournamespace].Hashing`.
5. To use the extension, just type: `using [yournamespace].Hahsing`.

Everything is setup correctly now.

> *NOTE: It's not neccessary to include the Hashing namespace within your own namespace, then you can just use this: `using Hashing`. BUT just make sure it's included in your `.sln` or makefile.*
