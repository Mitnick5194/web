#! /bin/bash
reason=$1
git add .
if test -z $reason
then
	echo "提交失败"
	echo "[usage] ./push.sh '提交理由' "
	exit 2
else
	git commit -m $reason
fi
git push
