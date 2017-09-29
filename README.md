# csc480 project1 README

## To Push Changes
1. Push the changes to own branch
	- `git add <file>`
	- `git commit -a -m <message>`
	- `git push`
2. Merge and push from master branch to master remote
	- `git checkout master`
	- `git merge <user branch>`
	- `git push`

## To Fetch Changes
1. Make sure local branch is updated
	- `git add <files>`
	- `git commit -a -m "message"`
	- `git push`
2. Pull from Master branch
	- `git checkout master`
	- `git pull`
3. Merge with Master from own branch and push
	- `git checkout <user branch>`
	- `git merge master`
	- `git push`

