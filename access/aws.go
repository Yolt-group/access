package main

import (
	"bytes"
	"io/ioutil"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
)

func newAWSSession(region string) (*session.Session, error) {
	s, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func getState(s *session.Session, bucket, key string) (string, error) {

	resp, err := s3.New(s).GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return "", errors.Wrapf(err, "failed s3:GetObject for bucket %s", bucket)
	}

	if resp.LastModified.Add(3 * time.Minute).Before(time.Now()) {
		return "", errors.New("session expired")
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed s3:GetObject for bucket %s", bucket)
	}

	return string(bytes), nil
}

func deleteState(s *session.Session, bucket, key string) error {

	_, err := s3.New(s).DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return errors.Wrapf(err, "failed s3:DeleteObject for bucket %s", bucket)
	}

	return nil
}

func putState(s *session.Session, kmsKeyID, bucket, key, value string) error {

	content := []byte(value)
	_, err := s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		ACL:           aws.String("private"),
		Body:          bytes.NewReader(content),
		ContentLength: aws.Int64(int64(len(content))),
		//	ContentType:          aws.String(http.DetectContentType(buffer)),
		//	ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("aws:kms"),
		SSEKMSKeyId:          aws.String(kmsKeyID),
	})

	if err != nil {
		return errors.Wrapf(err, "failed s3:PutObject for bucket %s", bucket)
	}

	return err
}
