#!/usr/bin/env python
# coding: utf-8

# anaconda3/bin/python3 Q2.py

	
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC

import warnings
warnings.filterwarnings("ignore")

df = pd.read_csv('Data/slowloris.csv')
df.drop(columns=['frame.protocols','ip.src','ip.dst'],inplace=True)
df.insert(column='Label',loc=26,value=1)

df1 = pd.read_csv('Data/normal.csv')
df1.drop(columns=['Unnamed: 0'],inplace=True)
df1.drop(columns=['frame.protocols','ip.src','ip.dst'],inplace=True)
df1.Label=0


df2 = pd.read_csv('Data/httpflood.csv')
df2.drop(columns=['frame.protocols','ip.src','ip.dst'],inplace=True)
df2.insert(column='Label',loc=26,value=1)

df_merged = pd.concat([df,df1,df2])
y = df_merged.Label

x_train,x_test,y_train,y_test = train_test_split(df_merged,y,test_size=0.3,random_state=42)
x_train.drop(columns='Label',inplace=True)
x_test.drop(columns='Label',inplace=True)

model1 = DecisionTreeClassifier(random_state=42)
print("Training Decision Tree...")
print("")
model1.fit(x_train,y_train)
print("Testing Decision Tree...")
print("")
pred = model1.predict(x_test)
print("Accuracy: ",accuracy_score(y_pred=pred,y_true=y_test))
print("Precision: ",precision_score(y_pred=pred,y_true=y_test))
print("Recall: ",recall_score(y_pred=pred,y_true=y_test))
print("F1 score: ",f1_score(y_pred=pred,y_true=y_test))
print("")

model2 = SVC(random_state=42)
print("Training SVM..")
print("")
model2.fit(x_train,y_train)
print("Testing SVM...")
pred = model2.predict(x_test)
print("Accuracy: ",accuracy_score(y_pred=pred,y_true=y_test))
print("Precision: ",precision_score(y_pred=pred,y_true=y_test))
print("Recall: ",recall_score(y_pred=pred,y_true=y_test))
print("F1 score: ",f1_score(y_pred=pred,y_true=y_test))
print("")


df4 = pd.read_csv('Data/captured1.csv')
df4.drop(columns=['frame.protocols','ip.src','ip.dst'],inplace=True)

predictions = model1.predict(df4)
df4.insert(column='Label',loc=26,value=predictions)
df4.to_csv("predtree1.csv")
print("Predictions saved to predtree1.csv")
print("")

df4.drop(columns=['Label'],inplace=True)

predictions = model2.predict(df4)
df4.insert(column='Label',loc=26,value=predictions)
df4.to_csv("predsvm1.csv")
print("Predictions saved to predsvm1.csv")
print("")


df5 = pd.read_csv('Data/pcapanalysis.csv')
df5.drop(columns=['frame.protocols','ip.src','ip.dst'],inplace=True)

predictions1 = model1.predict(df5)
df5.insert(column='Label',loc=26,value=predictions1)
df5.to_csv("predtree1.csv")
print("Predictions saved to predtree2.csv")
print("")

df5.drop(columns=['Label'],inplace=True)

predictions1 = model2.predict(df5)
df5.insert(column='Label',loc=26,value=predictions1)
df5.to_csv("predsvm2.csv")
print("Predictions saved to predsvm2.csv")
print("")

df = pd.read_csv('Data/slowloris.csv')
df6 = pd.read_csv('Data/captured3.csv')
df6.drop(columns=['Unnamed: 0'],inplace=True)
df6.drop(columns=['frame.protocols','ip.src','ip.dst','Label'],inplace=True)

predictions2 = model1.predict(df6)

pred0 = []
pred1 = []
for i in predictions2:
    if i==1:
        pred1.append(i)
    else:
        pred0.append(i)

df6.insert(column='Label',loc=26,value=predictions2)
df6.to_csv("predtree3.csv")
print("Predictions saved to predtree3.csv")
print("")
print("Displaying predictions count:")
print("")
print("Normal Count: ",len(pred0))
print("Malicious Count:",len(pred1))
print("")

df6.drop(columns=['Label'],inplace=True)

predictions2 = model2.predict(df6)
pred0 = []
pred1 = []
for i in predictions2:
    if i==1:
        pred1.append(i)
    else:
        pred0.append(i)

df6.insert(column='Label',loc=26,value=predictions2)
df6.to_csv("predsvm3.csv")
print("Predictions saved to predsvm3.csv")
print("")
print("Displaying predictions count:")
print("")
print("Normal Count: ",len(pred0))
print("Malicious Count:",len(pred1))
print("")


df8 = pd.read_csv('Data/captured2.csv')


predictions4 = model1.predict(df8.drop(columns=['frame.protocols','ip.src','ip.dst']))
df8.insert(column='Label',loc=29,value=predictions4)
df8.to_csv("finaltree.csv")
print("Final predictions saved to finaltree.csv")
print("")

df8.drop(columns=['Label'],inplace=True)

predictions4 = model2.predict(df8.drop(columns=['frame.protocols','ip.src','ip.dst']))
df8.insert(column='Label',loc=29,value=predictions4)
df8.to_csv("finalsvm.csv")
print("Final predictions saved to finalsvm.csv")
print("")





